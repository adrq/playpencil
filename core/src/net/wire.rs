use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;

const MAX_FRAME_LEN: usize = 65535;

/// Tracks partial read progress across poll iterations.
///
/// Reads length-prefixed Ethernet frames from a non-blocking SOCK_STREAM.
/// Survives WouldBlock between the length prefix and body.
pub struct FrameReader {
    state: ReadState,
}

enum ReadState {
    /// Waiting for (or partially through) the 4-byte length prefix.
    ReadingLength { buf: [u8; 4], filled: usize },
    /// Have the length, waiting for the frame body.
    ReadingBody { buf: Vec<u8>, filled: usize },
}

impl FrameReader {
    pub fn new() -> Self {
        Self {
            state: ReadState::ReadingLength {
                buf: [0; 4],
                filled: 0,
            },
        }
    }

    /// Try to read a complete frame. Returns:
    /// - `Ok(Some(frame))` when a full frame is ready
    /// - `Ok(None)` when idle or waiting for more bytes
    /// - `Err` for real I/O faults or protocol errors
    pub fn poll(&mut self, socket: &mut UnixStream) -> io::Result<Option<Vec<u8>>> {
        loop {
            match &mut self.state {
                ReadState::ReadingLength { buf, filled } => {
                    match socket.read(&mut buf[*filled..]) {
                        Ok(0) => {
                            return if *filled == 0 {
                                // Clean EOF at frame boundary — VM socket closed
                                Err(io::Error::new(
                                    io::ErrorKind::ConnectionReset,
                                    "connection closed",
                                ))
                            } else {
                                Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "connection closed mid-length",
                                ))
                            };
                        }
                        Ok(n) => {
                            *filled += n;
                            if *filled < 4 {
                                return Ok(None);
                            }
                            let frame_len = u32::from_be_bytes(*buf) as usize;
                            if frame_len == 0 || frame_len > MAX_FRAME_LEN {
                                self.state = ReadState::ReadingLength {
                                    buf: [0; 4],
                                    filled: 0,
                                };
                                return Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    format!("invalid frame length: {frame_len}"),
                                ));
                            }
                            self.state = ReadState::ReadingBody {
                                buf: vec![0u8; frame_len],
                                filled: 0,
                            };
                            // Fall through to ReadingBody
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(None),
                        Err(e) => return Err(e),
                    }
                }
                ReadState::ReadingBody { buf, filled } => {
                    match socket.read(&mut buf[*filled..]) {
                        Ok(0) => {
                            return Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "connection closed mid-frame",
                            ));
                        }
                        Ok(n) => {
                            *filled += n;
                            if *filled < buf.len() {
                                return Ok(None);
                            }
                            // Frame complete — take it and reset state
                            let frame = std::mem::take(buf);
                            self.state = ReadState::ReadingLength {
                                buf: [0; 4],
                                filled: 0,
                            };
                            return Ok(Some(frame));
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(None),
                        Err(e) => return Err(e),
                    }
                }
            }
        }
    }
}

/// Writes length-prefixed frames using temporary blocking mode.
pub struct FrameWriter;

impl FrameWriter {
    pub fn write_frame(socket: &mut UnixStream, frame: &[u8]) -> io::Result<()> {
        let len = (frame.len() as u32).to_be_bytes();
        socket.set_nonblocking(false)?;
        let result = socket
            .write_all(&len)
            .and_then(|()| socket.write_all(frame));
        // Always restore nonblocking mode, even on write failure
        socket.set_nonblocking(true)?;
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    #[test]
    fn test_write_read_frame_roundtrip() {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        b.set_nonblocking(true).unwrap();
        let payload = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02];
        FrameWriter::write_frame(&mut a, &payload).unwrap();

        let mut reader = FrameReader::new();
        let frame = reader.poll(&mut b).unwrap().unwrap();
        assert_eq!(frame, payload);
    }

    #[test]
    fn test_read_frame_nonblocking_returns_none() {
        let (_a, mut b) = UnixStream::pair().unwrap();
        b.set_nonblocking(true).unwrap();
        let mut reader = FrameReader::new();
        assert!(reader.poll(&mut b).unwrap().is_none());
    }

    #[test]
    fn test_read_frame_invalid_length() {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        b.set_nonblocking(true).unwrap();
        // Write length = 0
        a.write_all(&0u32.to_be_bytes()).unwrap();
        let mut reader = FrameReader::new();
        let err = reader.poll(&mut b).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("invalid frame length: 0"));
    }

    #[test]
    fn test_write_read_multiple_frames() {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        b.set_nonblocking(true).unwrap();
        let frames: Vec<Vec<u8>> = vec![vec![1, 2, 3], vec![4, 5], vec![6, 7, 8, 9]];
        for f in &frames {
            FrameWriter::write_frame(&mut a, f).unwrap();
        }
        let mut reader = FrameReader::new();
        for expected in &frames {
            let got = reader.poll(&mut b).unwrap().unwrap();
            assert_eq!(&got, expected);
        }
    }

    #[test]
    fn test_partial_length_prefix() {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        b.set_nonblocking(true).unwrap();
        let payload = vec![0xAA; 10];
        let len_bytes = (payload.len() as u32).to_be_bytes();

        // Write first 2 bytes of length prefix
        a.write_all(&len_bytes[..2]).unwrap();
        let mut reader = FrameReader::new();
        assert!(reader.poll(&mut b).unwrap().is_none());

        // Write remaining 2 bytes + full payload
        a.write_all(&len_bytes[2..]).unwrap();
        a.write_all(&payload).unwrap();
        let frame = reader.poll(&mut b).unwrap().unwrap();
        assert_eq!(frame, payload);
    }

    #[test]
    fn test_partial_frame_body() {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        b.set_nonblocking(true).unwrap();
        let payload = vec![0xBB; 20];
        let len_bytes = (payload.len() as u32).to_be_bytes();

        // Write length prefix + partial payload
        a.write_all(&len_bytes).unwrap();
        a.write_all(&payload[..8]).unwrap();
        let mut reader = FrameReader::new();
        assert!(reader.poll(&mut b).unwrap().is_none());

        // Write remaining payload
        a.write_all(&payload[8..]).unwrap();
        let frame = reader.poll(&mut b).unwrap().unwrap();
        assert_eq!(frame, payload);
    }
}
