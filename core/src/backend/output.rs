//! Durable, full-retention capture of a sandbox main process's stdout/stderr.
//!
//! The on-disk format is a sequence of length-prefixed records
//! `[stream:u8][len:u32-le][raw bytes]` written host-side to a session-dir file.
//! The framing keeps the two streams ordered, tagged, and byte-exact. It is an
//! INTERNAL binary format: callers read it back as decoded [`OutputChunk`]s
//! through [`read_capture`], so the storage layout stays private to the backend.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

/// On-disk stream tag for stdout.
const STREAM_STDOUT: u8 = 0;
/// On-disk stream tag for stderr.
const STREAM_STDERR: u8 = 1;

/// Which of a process's two output streams a chunk came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputStream {
    Stdout,
    Stderr,
}

/// One decoded, stream-tagged output chunk, in arrival order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputChunk {
    pub stream: OutputStream,
    pub bytes: Vec<u8>,
}

/// A decoded snapshot of a sandbox's captured output: every chunk in arrival
/// order, interleaving stdout and stderr exactly as they were written.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OutputSnapshot {
    pub chunks: Vec<OutputChunk>,
}

/// Run-scoped writer that appends captured output to a session-dir file. Created
/// (truncating any prior run's file) at launch and owned by the running VM, so it
/// unwinds with the VM. Write errors are surfaced to the caller, which keeps
/// draining rather than wedging the workload.
pub struct OutputCapture {
    file: File,
    /// The capture file's parent directory, fsync'd on `finalize` so a
    /// newly-created file's directory entry is crash-durable.
    dir: PathBuf,
}

impl OutputCapture {
    /// Open `path` for the current run, truncating any prior content. A failure
    /// here is an error in our own session dir and must fail the start loudly.
    /// The file is owner-only (0600): it can hold secrets/tool output from the
    /// main process, matching the durable state file's discipline.
    pub fn create(path: &Path) -> io::Result<Self> {
        use std::os::unix::fs::OpenOptionsExt;
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        let dir = match path.parent() {
            Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
            _ => PathBuf::from("."),
        };
        Ok(Self { file, dir })
    }

    /// Append one stdout chunk as a length-prefixed record.
    pub fn write_stdout(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.write_record(STREAM_STDOUT, bytes)
    }

    /// Append one stderr chunk as a length-prefixed record.
    pub fn write_stderr(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.write_record(STREAM_STDERR, bytes)
    }

    /// Flush the captured output to disk (fsync) AND fsync the parent directory,
    /// so a file created this run has a crash-durable directory entry. Called once
    /// on the controlled exit path, before the paired terminal outcome is
    /// reported, so the capture is durable no later than the terminal record it is
    /// paired with (which is itself directory-fsync durable via the store).
    pub fn finalize(&mut self) -> io::Result<()> {
        self.file.sync_all()?;
        File::open(&self.dir)?.sync_all()
    }

    fn write_record(&mut self, stream: u8, bytes: &[u8]) -> io::Result<()> {
        let len: u32 = bytes
            .len()
            .try_into()
            .map_err(|_| io::Error::other("capture chunk exceeds u32 length"))?;
        let mut header = [0u8; 5];
        header[0] = stream;
        header[1..5].copy_from_slice(&len.to_le_bytes());
        self.file.write_all(&header)?;
        self.file.write_all(bytes)
    }
}

/// Read and decode a capture file. Returns `None` if the file does not exist (no
/// run captured output yet, or the backend has no capture). An abrupt kill can
/// leave a torn trailing record; decoding stops at the first incomplete record
/// and returns the valid prefix rather than failing the whole read.
pub fn read_capture(path: &Path) -> io::Result<Option<OutputSnapshot>> {
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    Ok(Some(decode(&data)))
}

/// Decode the length-prefixed record stream, tolerating a truncated tail and an
/// unrecognized stream tag (both treated as the end of valid data).
fn decode(data: &[u8]) -> OutputSnapshot {
    let mut chunks = Vec::new();
    let mut off = 0usize;
    while off + 5 <= data.len() {
        let stream = match data[off] {
            STREAM_STDOUT => OutputStream::Stdout,
            STREAM_STDERR => OutputStream::Stderr,
            // An unknown tag means corruption/truncation: stop at the valid prefix.
            _ => break,
        };
        let len = u32::from_le_bytes([data[off + 1], data[off + 2], data[off + 3], data[off + 4]])
            as usize;
        let start = off + 5;
        let Some(end) = start.checked_add(len) else {
            break;
        };
        if end > data.len() {
            // Trailing record is truncated: return everything before it.
            break;
        }
        chunks.push(OutputChunk {
            stream,
            bytes: data[start..end].to_vec(),
        });
        off = end;
    }
    OutputSnapshot { chunks }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path() -> std::path::PathBuf {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        std::env::temp_dir().join(format!("pp-capture-{}-{n}.bin", std::process::id()))
    }

    #[test]
    fn roundtrip_is_byte_exact_and_ordered() {
        let path = tmp_path();
        let mut cap = OutputCapture::create(&path).unwrap();
        // Non-UTF-8 and NUL bytes must survive, and stdout/stderr must interleave
        // in exactly the order written.
        cap.write_stdout(b"out1").unwrap();
        cap.write_stderr(&[0xff, 0x00, 0xfe]).unwrap();
        cap.write_stdout(b"").unwrap();
        cap.write_stderr(b"err2").unwrap();
        drop(cap);

        let snap = read_capture(&path).unwrap().unwrap();
        assert_eq!(
            snap.chunks,
            vec![
                OutputChunk {
                    stream: OutputStream::Stdout,
                    bytes: b"out1".to_vec()
                },
                OutputChunk {
                    stream: OutputStream::Stderr,
                    bytes: vec![0xff, 0x00, 0xfe]
                },
                OutputChunk {
                    stream: OutputStream::Stdout,
                    bytes: vec![]
                },
                OutputChunk {
                    stream: OutputStream::Stderr,
                    bytes: b"err2".to_vec()
                },
            ]
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn truncated_tail_decodes_to_valid_prefix() {
        let path = tmp_path();
        let mut cap = OutputCapture::create(&path).unwrap();
        cap.write_stdout(b"complete").unwrap();
        drop(cap);
        // Append a torn record: a header claiming 100 bytes followed by only 3.
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        let mut hdr = [0u8; 5];
        hdr[0] = STREAM_STDOUT;
        hdr[1..5].copy_from_slice(&100u32.to_le_bytes());
        f.write_all(&hdr).unwrap();
        f.write_all(b"abc").unwrap();
        drop(f);

        let snap = read_capture(&path).unwrap().unwrap();
        assert_eq!(
            snap.chunks,
            vec![OutputChunk {
                stream: OutputStream::Stdout,
                bytes: b"complete".to_vec()
            }]
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn missing_file_is_none() {
        let path = tmp_path();
        assert!(read_capture(&path).unwrap().is_none());
    }

    #[test]
    fn create_makes_owner_only_capture_file() {
        use std::os::unix::fs::PermissionsExt;
        // The capture can hold secrets/tool output, so it must be 0600 like the
        // durable state file — never world/group readable.
        let path = tmp_path();
        let _cap = OutputCapture::create(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "capture file must be 0600");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn finalize_fsyncs_file_and_parent_and_keeps_content() {
        // finalize() fsyncs the file AND opens+fsyncs the parent directory (so a
        // newly-created file's directory entry is durable). fsync durability
        // itself isn't observable, but the parent open+sync must succeed and the
        // content must remain intact + readable.
        let dir = std::env::temp_dir().join(format!("pp-capdir-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("entrypoint-capture.bin");
        let mut cap = OutputCapture::create(&path).unwrap();
        cap.write_stdout(b"durable").unwrap();
        cap.finalize()
            .expect("finalize must fsync file + parent dir");
        drop(cap);
        let snap = read_capture(&path).unwrap().unwrap();
        assert_eq!(snap.chunks.len(), 1);
        assert_eq!(snap.chunks[0].bytes, b"durable");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn create_truncates_prior_run() {
        let path = tmp_path();
        let mut cap = OutputCapture::create(&path).unwrap();
        cap.write_stdout(b"old run").unwrap();
        drop(cap);
        // A fresh capture for a new run overwrites the prior file.
        let mut cap = OutputCapture::create(&path).unwrap();
        cap.write_stdout(b"new").unwrap();
        drop(cap);
        let snap = read_capture(&path).unwrap().unwrap();
        assert_eq!(
            snap.chunks,
            vec![OutputChunk {
                stream: OutputStream::Stdout,
                bytes: b"new".to_vec()
            }]
        );
        std::fs::remove_file(&path).ok();
    }
}
