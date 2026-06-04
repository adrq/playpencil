//! Incremental UTF-8 decoding for the text command face.
//!
//! Raw process bytes arrive in arbitrary chunks that may split a multi-byte
//! codepoint. The decoder emits the longest valid text it can and carries the
//! trailing incomplete bytes to the next push, so a split codepoint never
//! produces a spurious replacement character. It also reports how many RAW
//! process bytes each emission represents, which is the unit of output credit.

/// Per-stream incremental UTF-8 decoder (stdout and stderr decode separately).
#[derive(Default)]
pub(crate) struct Utf8StreamDecoder {
    carry: Vec<u8>,
}

impl Utf8StreamDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Decode `bytes` (prefixed by any carried partial codepoint). Returns the
    /// emitted text and the number of RAW bytes it represents — i.e. the bytes
    /// turned into text or into a replacement character, EXCLUDING bytes newly
    /// held in the carry. Invalid bytes become `U+FFFD` but are still counted as
    /// represented (so credit is released for them).
    pub fn push(&mut self, bytes: &[u8]) -> (String, usize) {
        let mut buf = std::mem::take(&mut self.carry);
        let prev_carry = buf.len();
        buf.extend_from_slice(bytes);

        let mut out = String::new();
        let mut consumed = 0;
        while consumed < buf.len() {
            let rest = &buf[consumed..];
            match std::str::from_utf8(rest) {
                Ok(s) => {
                    out.push_str(s);
                    consumed = buf.len();
                    break;
                }
                Err(e) => {
                    let valid = e.valid_up_to();
                    if valid > 0 {
                        // SAFETY: `valid_up_to` is a guaranteed valid boundary.
                        out.push_str(unsafe { std::str::from_utf8_unchecked(&rest[..valid]) });
                    }
                    match e.error_len() {
                        // Incomplete trailing sequence: hold it for the next push.
                        None => {
                            consumed += valid;
                            break;
                        }
                        // Invalid sequence: emit one replacement, skip it, continue.
                        Some(n) => {
                            out.push('\u{FFFD}');
                            consumed += valid + n;
                        }
                    }
                }
            }
        }

        self.carry = buf[consumed..].to_vec();
        // Raw bytes represented by this push = (prev carry + new bytes) - new carry.
        let raw = prev_carry + bytes.len() - self.carry.len();
        (out, raw)
    }

    /// Flush any residual carry at end-of-stream as a single replacement
    /// character; the raw count is the carried byte length.
    pub fn flush(&mut self) -> (String, usize) {
        if self.carry.is_empty() {
            return (String::new(), 0);
        }
        let n = self.carry.len();
        self.carry.clear();
        ("\u{FFFD}".to_string(), n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_codepoint_holds_carry_no_spurious_replacement() {
        let mut d = Utf8StreamDecoder::new();
        // "é" = 0xC3 0xA9 split across two pushes.
        let (t1, r1) = d.push(&[0xC3]);
        assert_eq!(t1, "");
        assert_eq!(r1, 0, "the carried lead byte is not yet represented");
        let (t2, r2) = d.push(&[0xA9]);
        assert_eq!(t2, "é");
        assert_eq!(r2, 2, "both raw bytes represented once completed");
    }

    #[test]
    fn invalid_byte_emits_single_replacement_counted_once() {
        let mut d = Utf8StreamDecoder::new();
        let (t, raw) = d.push(&[b'a', 0xFF, b'b']);
        assert_eq!(t, "a\u{FFFD}b");
        // 'a' (1) + invalid 0xFF (1) + 'b' (1) = 3 raw, NOT counting FFFD as 3.
        assert_eq!(raw, 3);
    }

    #[test]
    fn flush_residual_carry_emits_one_replacement() {
        let mut d = Utf8StreamDecoder::new();
        let (t, r) = d.push(&[0xE2, 0x82]); // first two of a 3-byte codepoint
        assert_eq!(t, "");
        assert_eq!(r, 0);
        let (ft, fr) = d.flush();
        assert_eq!(ft, "\u{FFFD}");
        assert_eq!(fr, 2, "raw count of the dropped carry");
        // Flush is idempotent on an empty carry.
        assert_eq!(d.flush(), (String::new(), 0));
    }

    #[test]
    fn carried_then_completed_raw_count_excludes_then_includes() {
        let mut d = Utf8StreamDecoder::new();
        // "ab" + lead of "€" (0xE2) then the rest.
        let (t1, r1) = d.push(b"ab\xE2");
        assert_eq!(t1, "ab");
        assert_eq!(r1, 2, "the held lead byte is not represented yet");
        let (t2, r2) = d.push(&[0x82, 0xAC]);
        assert_eq!(t2, "€");
        assert_eq!(r2, 3, "carried lead + the two new bytes");
    }

    #[test]
    fn pure_ascii_passthrough() {
        let mut d = Utf8StreamDecoder::new();
        let (t, r) = d.push(b"hello");
        assert_eq!(t, "hello");
        assert_eq!(r, 5);
    }
}
