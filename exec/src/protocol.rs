//! The exec wire protocol: frames, base64 [`codec`], flow-control [`limits`], and
//! the frame-size boundary predicates. Always compiled (no feature gate), pure
//! data + serde — no runtime, no libc, no tokio, platform-neutral.
//!
//! This unifies what used to be duplicated host-vs-guest: two frame-enum pairs
//! (`HostMsg`/`GuestMsg` in the libkrun backend and `HostMessage`/`GuestMessage`
//! in init), two base64 implementations, and three copies of the flow-control
//! constants. They are now a single bidirectional [`HostFrame`]/[`GuestFrame`]
//! pair, one [`codec`], and one [`limits`] source of truth — keeping the
//! host/guest credit contract drift-proof. The wire bytes are unchanged.

use serde::{Deserialize, Serialize};

/// Base64 (standard alphabet) used for binary stdin/stdout/stderr payloads on the
/// newline-JSON wire. The decoder is intentionally permissive (accepts input with
/// the trailing `=` padding omitted); preserved exactly from the prior host/guest
/// copies so the wire format is byte-identical.
pub mod codec {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    pub fn base64_encode(data: &[u8]) -> String {
        let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
        for chunk in data.chunks(3) {
            let b0 = chunk[0] as u32;
            let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
            let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
            let triple = (b0 << 16) | (b1 << 8) | b2;
            out.push(ALPHABET[((triple >> 18) & 0x3F) as usize] as char);
            out.push(ALPHABET[((triple >> 12) & 0x3F) as usize] as char);
            out.push(if chunk.len() > 1 {
                ALPHABET[((triple >> 6) & 0x3F) as usize] as char
            } else {
                '='
            });
            out.push(if chunk.len() > 2 {
                ALPHABET[(triple & 0x3F) as usize] as char
            } else {
                '='
            });
        }
        out
    }

    /// Decode standard base64. Returns `None` on invalid input. Accepts input with
    /// the trailing `=` padding omitted.
    pub fn base64_decode(input: &str) -> Option<Vec<u8>> {
        let without_pad = input.trim_end_matches('=');
        let pad = (4 - without_pad.len() % 4) % 4;
        if pad > 2 {
            return None;
        }
        fn val(c: char) -> Option<u32> {
            match c {
                'A'..='Z' => Some(c as u32 - 'A' as u32),
                'a'..='z' => Some(c as u32 - 'a' as u32 + 26),
                '0'..='9' => Some(c as u32 - '0' as u32 + 52),
                '+' => Some(62),
                '/' => Some(63),
                _ => None,
            }
        }
        let chars: Vec<char> = without_pad.chars().collect();
        let mut out = Vec::with_capacity((chars.len() * 3) / 4 + 1);
        let mut i = 0;
        while i < chars.len() {
            let v0 = val(chars[i])?;
            let v1 = if i + 1 < chars.len() {
                val(chars[i + 1])?
            } else {
                0
            };
            let v2 = if i + 2 < chars.len() {
                val(chars[i + 2])?
            } else {
                0
            };
            let v3 = if i + 3 < chars.len() {
                val(chars[i + 3])?
            } else {
                0
            };
            let triple = (v0 << 18) | (v1 << 12) | (v2 << 6) | v3;
            out.push(((triple >> 16) & 0xFF) as u8);
            if i + 2 < chars.len() {
                out.push(((triple >> 8) & 0xFF) as u8);
            }
            if i + 3 < chars.len() {
                out.push((triple & 0xFF) as u8);
            }
            i += 4;
        }
        Some(out)
    }
}

/// The flow-control constants that form the host/guest credit contract. One
/// source of truth, shared by the producer (guest), the relay (host), and the
/// consumer edge.
pub mod limits {
    /// Per-id outstanding-stdin-bytes cap (the credit window) shared by host and
    /// guest: the host never has more than this many un-acknowledged stdin bytes
    /// in flight to one exec, and the guest never buffers more than this for one.
    pub const INPUT_WINDOW: usize = 256 * 1024;

    /// Maximum raw bytes carried by a single stdin FRAME. The byte-bounded stdin
    /// ingress splits caller input into pieces no larger than this, so no single
    /// call buffers an unbounded `Vec` and a frame's base64 form stays under the
    /// console frame cap.
    pub const STDIN_FRAME_RAW_MAX: usize = 64 * 1024;

    /// The guest batches stdin CREDIT grants: it grants the host more send-credit
    /// only once the bytes it has drained to the child reach this threshold.
    ///
    /// Semantically DISTINCT from [`STDIN_FRAME_RAW_MAX`] even though both equal
    /// 64 KiB today — one sizes a single host→guest frame, the other batches
    /// guest→host credit grants. Keep them separate; do not collapse the two.
    pub const CREDIT_GRANT_THRESHOLD: usize = INPUT_WINDOW / 4;

    /// Pause a child's output once this many raw bytes are outstanding (between
    /// the guest and the point the consumer has yielded them downstream).
    pub const OUTPUT_HIGH: usize = 256 * 1024;
    /// Resume a paused child once outstanding falls below this.
    pub const OUTPUT_LOW: usize = 64 * 1024;

    /// Maximum bytes in one newline-delimited wire frame (excluding the newline).
    pub const MAX_FRAME_BYTES: usize = 1024 * 1024;
}

/// How the guest interprets an exec command vector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecMode {
    /// `cmd` is an argv vector run directly via `execvp(cmd[0], cmd)`.
    #[default]
    Argv,
    /// `cmd[0]` is a shell line run via the resolved shell (`-c`).
    Shell,
}

/// host → guest frames. Serialized by the host (relay), deserialized by the guest
/// (producer). The additive fields on `Exec` carry `#[serde(default)]` so an old
/// host that omits them still deserializes on the guest; serialization is
/// unaffected and still emits every field (including explicit `null`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HostFrame {
    Exec {
        id: String,
        cmd: Vec<String>,
        #[serde(default)]
        env: Vec<String>,
        #[serde(default)]
        workdir: Option<String>,
        #[serde(default)]
        uid: Option<u32>,
        #[serde(default)]
        gid: Option<u32>,
        #[serde(default)]
        mode: ExecMode,
    },
    Stdin {
        id: String,
        data: String,
    },
    Signal {
        id: String,
        signal: i32,
    },
    /// Terminal resize. A forward seam: the guest treats it as a NO-OP today (no
    /// pty), but the frame is part of the wire contract.
    Resize {
        id: String,
        cols: u32,
        rows: u32,
    },
    /// Output flow-control: the guest stops reading this child's stdout/stderr.
    Pause {
        id: String,
    },
    /// Output flow-control: the guest resumes reading this child's output.
    Resume {
        id: String,
    },
}

/// guest → host frames. Serialized by the guest (producer), deserialized by the
/// host (relay).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum GuestFrame {
    Stdout {
        id: String,
        data: String,
    },
    Stderr {
        id: String,
        data: String,
    },
    Exit {
        id: String,
        code: i32,
    },
    /// The command never started as intended (distinct from a numeric exit).
    StartError {
        id: String,
        message: String,
    },
    /// Input flow-control: grant the host `bytes` more stdin send-credit.
    StdinCredit {
        id: String,
        bytes: usize,
    },
    /// The guest closed/discarded the child's stdin while the process keeps
    /// running, so the host must stop sending stdin for this id.
    StdinClosed {
        id: String,
    },
}

// Frame-boundary semantics are NOT uniform and MUST be preserved. The OUTBOUND
// host exec serialize rejects `len >= MAX_FRAME_BYTES` (it reserves room for the
// appended newline), while INBOUND readers reject only `len > MAX_FRAME_BYTES`
// (the newline is already excluded). These are distinct predicates — do NOT
// normalize `>=` into `>`.

/// True if an outbound JSON frame body is too large to send (reserves room for
/// the trailing newline): `json_len >= MAX_FRAME_BYTES`.
pub fn outbound_json_frame_too_large(json_len: usize) -> bool {
    json_len >= limits::MAX_FRAME_BYTES
}

/// True if an inbound frame body (newline already excluded) is too large to
/// accept: `len > MAX_FRAME_BYTES`.
pub fn inbound_frame_too_large(len: usize) -> bool {
    len > limits::MAX_FRAME_BYTES
}

#[cfg(test)]
mod golden_parity_tests {
    //! Byte-identity guards for the unified protocol. These assert the NEW types
    //! reproduce the EXACT wire bytes the old duplicated host/guest types
    //! produced — tag names, field order, explicit `null` fields, default-mode
    //! serialization, the permissive base64, and the `>=`/`>` frame-size split.
    //! They gate the deletion of the old types.
    use super::*;

    // --- base64 codec (was core/src/util.rs + init/src/proto.rs, identical) ---

    #[test]
    fn base64_known_vectors() {
        assert_eq!(codec::base64_encode(b""), "");
        assert_eq!(codec::base64_encode(b"A"), "QQ==");
        assert_eq!(codec::base64_encode(b"AB"), "QUI=");
        assert_eq!(codec::base64_encode(b"ABC"), "QUJD");
        assert_eq!(
            codec::base64_encode(b"Hello, World!"),
            "SGVsbG8sIFdvcmxkIQ=="
        );
    }

    #[test]
    fn base64_roundtrip_binary() {
        let data = b"hello\x00\xff\x7f";
        assert_eq!(
            codec::base64_decode(&codec::base64_encode(data)).unwrap(),
            data
        );
    }

    #[test]
    fn base64_decode_is_permissive_and_validating() {
        // Padding may be omitted.
        assert_eq!(codec::base64_decode("QQ").unwrap(), b"A");
        assert_eq!(codec::base64_decode("QUI").unwrap(), b"AB");
        // Invalid characters are rejected.
        assert!(codec::base64_decode("!!!!").is_none());
    }

    /// The FFI C-ABI exec-event path base64-encodes stdout/stderr `data`. Its
    /// output must be byte-identical to the old `crate::util::base64_encode`, or
    /// the C ABI would change. This is the exact vector the FFI test asserts.
    #[test]
    fn base64_matches_ffi_c_abi_vector() {
        assert_eq!(codec::base64_encode(b"hello"), "aGVsbG8=");
        // base64("out") == "b3V0" (the GuestFrame::Stdout golden below).
        assert_eq!(codec::base64_encode(b"out"), "b3V0");
    }

    // --- HostFrame serialization (was HostMsg in libkrun.rs) ---

    /// The host emits every Exec field, with `workdir`/`uid`/`gid` as explicit
    /// `null` and `mode` present even when default — exact field order.
    #[test]
    fn host_exec_emits_all_fields_with_nulls_and_default_mode() {
        let f = HostFrame::Exec {
            id: "e1".into(),
            cmd: vec!["echo".into(), "hi".into()],
            env: vec!["FOO=1".into()],
            workdir: None,
            uid: None,
            gid: None,
            mode: ExecMode::Argv,
        };
        assert_eq!(
            serde_json::to_string(&f).unwrap(),
            r#"{"type":"exec","id":"e1","cmd":["echo","hi"],"env":["FOO=1"],"workdir":null,"uid":null,"gid":null,"mode":"argv"}"#
        );
    }

    #[test]
    fn host_exec_shell_mode_and_creds() {
        let f = HostFrame::Exec {
            id: "e3".into(),
            cmd: vec!["echo hi | wc -c".into()],
            env: vec![],
            workdir: Some("/tmp".into()),
            uid: Some(1000),
            gid: Some(2000),
            mode: ExecMode::Shell,
        };
        assert_eq!(
            serde_json::to_string(&f).unwrap(),
            r#"{"type":"exec","id":"e3","cmd":["echo hi | wc -c"],"env":[],"workdir":"/tmp","uid":1000,"gid":2000,"mode":"shell"}"#
        );
    }

    #[test]
    fn host_other_variants_serialize_exactly() {
        assert_eq!(
            serde_json::to_string(&HostFrame::Stdin {
                id: "e1".into(),
                data: "aGVsbG8=".into()
            })
            .unwrap(),
            r#"{"type":"stdin","id":"e1","data":"aGVsbG8="}"#
        );
        assert_eq!(
            serde_json::to_string(&HostFrame::Signal {
                id: "e1".into(),
                signal: 9
            })
            .unwrap(),
            r#"{"type":"signal","id":"e1","signal":9}"#
        );
        assert_eq!(
            serde_json::to_string(&HostFrame::Resize {
                id: "e1".into(),
                cols: 80,
                rows: 24
            })
            .unwrap(),
            r#"{"type":"resize","id":"e1","cols":80,"rows":24}"#
        );
        assert_eq!(
            serde_json::to_string(&HostFrame::Pause { id: "e1".into() }).unwrap(),
            r#"{"type":"pause","id":"e1"}"#
        );
        assert_eq!(
            serde_json::to_string(&HostFrame::Resume { id: "e1".into() }).unwrap(),
            r#"{"type":"resume","id":"e1"}"#
        );
    }

    // --- HostFrame deserialization (was HostMessage in init/src/proto.rs) ---

    #[test]
    fn host_exec_deserialize_defaults_keep_old_hosts_compatible() {
        let f: HostFrame =
            serde_json::from_str(r#"{"type":"exec","id":"e2","cmd":["ls"]}"#).unwrap();
        match f {
            HostFrame::Exec {
                env,
                workdir,
                uid,
                gid,
                mode,
                ..
            } => {
                assert!(env.is_empty());
                assert_eq!(workdir, None);
                assert_eq!(uid, None);
                assert_eq!(gid, None);
                assert_eq!(mode, ExecMode::Argv);
            }
            _ => panic!("wrong variant"),
        }
    }

    // --- GuestFrame serialization (was GuestMessage in init/src/proto.rs) ---

    #[test]
    fn guest_variants_serialize_exactly() {
        assert_eq!(
            serde_json::to_string(&GuestFrame::Stdout {
                id: "e1".into(),
                data: codec::base64_encode(b"out")
            })
            .unwrap(),
            r#"{"type":"stdout","id":"e1","data":"b3V0"}"#
        );
        assert_eq!(
            serde_json::to_string(&GuestFrame::Stderr {
                id: "e1".into(),
                data: "ZXJy".into()
            })
            .unwrap(),
            r#"{"type":"stderr","id":"e1","data":"ZXJy"}"#
        );
        assert_eq!(
            serde_json::to_string(&GuestFrame::Exit {
                id: "e1".into(),
                code: 42
            })
            .unwrap(),
            r#"{"type":"exit","id":"e1","code":42}"#
        );
        assert_eq!(
            serde_json::to_string(&GuestFrame::StartError {
                id: "e1".into(),
                message: "no shell available".into()
            })
            .unwrap(),
            r#"{"type":"start_error","id":"e1","message":"no shell available"}"#
        );
        assert_eq!(
            serde_json::to_string(&GuestFrame::StdinCredit {
                id: "e1".into(),
                bytes: 4096
            })
            .unwrap(),
            r#"{"type":"stdin_credit","id":"e1","bytes":4096}"#
        );
        assert_eq!(
            serde_json::to_string(&GuestFrame::StdinClosed { id: "e1".into() }).unwrap(),
            r#"{"type":"stdin_closed","id":"e1"}"#
        );
    }

    // --- GuestFrame deserialization (was GuestMsg in libkrun.rs) ---

    #[test]
    fn guest_frame_deserialize_roundtrips() {
        let line = r#"{"type":"stdin_credit","id":"e9","bytes":65536}"#;
        let f: GuestFrame = serde_json::from_str(line).unwrap();
        assert_eq!(
            f,
            GuestFrame::StdinCredit {
                id: "e9".into(),
                bytes: 65536
            }
        );
    }

    // --- frame-size boundary operators (>= outbound vs > inbound) ---

    #[test]
    fn frame_size_boundary_operators_are_distinct() {
        let max = limits::MAX_FRAME_BYTES;
        // Outbound rejects AT the cap (reserving room for the newline): >=.
        assert!(!outbound_json_frame_too_large(max - 1));
        assert!(outbound_json_frame_too_large(max));
        assert!(outbound_json_frame_too_large(max + 1));
        // Inbound rejects only ABOVE the cap: >.
        assert!(!inbound_frame_too_large(max - 1));
        assert!(!inbound_frame_too_large(max));
        assert!(inbound_frame_too_large(max + 1));
    }

    #[test]
    fn credit_grant_threshold_is_distinct_from_stdin_frame_cap() {
        // Equal in value today, but they are different knobs — assert the value
        // each derivation yields so an accidental collapse is caught.
        assert_eq!(limits::CREDIT_GRANT_THRESHOLD, limits::INPUT_WINDOW / 4);
        assert_eq!(limits::CREDIT_GRANT_THRESHOLD, 64 * 1024);
        assert_eq!(limits::STDIN_FRAME_RAW_MAX, 64 * 1024);
    }
}
